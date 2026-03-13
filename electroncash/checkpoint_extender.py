# Copyright (c) 2026 The Electron Cash Developers
# Distributed under the MIT software license

"""
Automatic checkpoint extension and header pruning using MMR accumulator.

Extends the SPV checkpoint to recent height, enabling old headers to be
pruned and fetched on-demand with proofs. Keeps storage minimal as the
chain grows.

Lifecycle (once per app session):
1. On network init: bootstrap MMR from already-verified checkpoint proof
2. On shutdown: extend MMR with local headers, save new checkpoint, prune

The extension is trustless: MMR initialized from proof verified against
the current checkpoint, new headers verified locally. The extended
checkpoint inherits the trust level of the checkpoint it extends from.

Thread safety: All operations run on the Network thread.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List

from . import blockchain
from .bitcoin import Hash
from .util import PrintError, ensure_sparse_file

import os

if TYPE_CHECKING:
    from .network import Network
    from .simple_config import SimpleConfig

try:
    from .mmr_accumulator import MMRAccumulator
    MMR_AVAILABLE = True
except ImportError:
    MMR_AVAILABLE = False
    MMRAccumulator = None  # type: ignore[misc,assignment]

# How many blocks behind tip to set the new checkpoint (for reorg safety)
CHECKPOINT_SAFETY_MARGIN = 100

# Minimum blocks to extend before bothering to write new checkpoint
MIN_EXTENSION_BLOCKS = 1000

class CheckpointExtender(PrintError):
    """
    Manages automatic checkpoint extension and header pruning.

    Lifecycle:
    1. Created by Network if auto-extend is enabled
    2. bootstrap() called with verified checkpoint proof
    3. extend_and_save() called on shutdown
    4. prune_below_checkpoint() called after successful extension
    """

    def __init__(self, network: Network, config: SimpleConfig) -> None:
        self.network = network
        self.config = config
        self.accumulator: Optional[MMRAccumulator] = None
        self.bootstrap_height: Optional[int] = None
        self._bootstrapped = False
        self._extension_done = False

    def diagnostic_name(self) -> str:
        return "CheckpointExtender"

    def is_available(self) -> bool:
        """Check if MMR library is available."""
        return MMR_AVAILABLE

    def is_bootstrapped(self) -> bool:
        """Check if accumulator has been initialized from proof."""
        return self._bootstrapped

    def bootstrap(
        self,
        checkpoint_height: int,
        header_hex: str,
        merkle_branch: List[str]
    ) -> bool:
        """
        Initialize MMR accumulator from already-verified checkpoint proof.

        Called from on_block_headers after validate_checkpoint_result has
        confirmed the proof against our trusted checkpoint. Reuses the same
        proof data to initialize the MMR.

        Args:
            checkpoint_height: Height of the checkpoint block.
            header_hex: Hex-encoded 80-byte block header at checkpoint_height.
            merkle_branch: List of hex-encoded sibling hashes.

        Returns:
            True if bootstrap succeeded, False otherwise.
        """
        if not MMR_AVAILABLE:
            self.print_error("MMR library not available")
            return False

        if self._bootstrapped:
            # Already done, this is fine
            return True

        try:
            # Compute header hash (this is the last leaf in the MMR)
            header_bytes = bytes.fromhex(header_hex)
            if len(header_bytes) != blockchain.HEADER_SIZE:
                self.print_error("Invalid header size:", len(header_bytes))
                return False

            # Bitcoin uses double-SHA256 for block hashes
            header_hash = Hash(header_bytes)

            # Convert branch from hex strings to bytes
            # ElectrumX provides hashes in big-endian hex, MMR uses little-endian
            siblings: List[bytes] = []
            for item in merkle_branch:
                sibling_bytes = bytes.fromhex(item)
                if len(sibling_bytes) != 32:
                    self.print_error("Invalid sibling size:", len(sibling_bytes))
                    return False
                siblings.append(sibling_bytes[::-1])

            # leaf_count is checkpoint_height + 1 (heights are 0-indexed)
            leaf_count = checkpoint_height + 1

            # Bootstrap the accumulator
            self.accumulator = MMRAccumulator.bootstrap_from_proof(
                leaf_count=leaf_count,
                last_leaf=header_hash,
                siblings=siblings
            )

            if self.accumulator is None:
                self.print_error("bootstrap_from_proof returned None - invalid proof structure")
                return False

            self.bootstrap_height = checkpoint_height
            self._bootstrapped = True
            self.print_error(
                "Bootstrapped MMR at height", checkpoint_height,
                "leaves={}".format(self.accumulator.leaf_count),
                "peaks={}".format(self.accumulator.peak_count)
            )
            return True

        except Exception as e:
            self.print_error("Bootstrap failed:", repr(e))
            self.accumulator = None
            return False

    def extend_and_save(self) -> bool:
        """
        Extend MMR to near-tip and save new checkpoint to config.

        Called on shutdown. Reads headers from local storage, verifies
        chain linkage, extends the MMR, and writes the new checkpoint
        height and merkle root to config. Enables pruning of old headers.

        Returns:
            True if extension and save succeeded, False otherwise.
        """
        if self._extension_done:
            return True

        if not self._bootstrapped or self.accumulator is None:
            self.print_error("Cannot extend - not bootstrapped")
            return False

        if self.bootstrap_height is None:
            self.print_error("Cannot extend - bootstrap_height is None")
            return False

        try:
            chain = self.network.blockchain()
            if chain is None:
                self.print_error("No blockchain available")
                return False

            local_height = chain.height()
            target_height = local_height - CHECKPOINT_SAFETY_MARGIN

            if target_height <= self.bootstrap_height:
                self.print_error(
                    "Not enough headers: local={} bootstrap={}".format(
                        local_height, self.bootstrap_height
                    )
                )
                return False

            extension_count = target_height - self.bootstrap_height
            if extension_count < MIN_EXTENSION_BLOCKS:
                self.print_error(
                    "Extension too small ({} blocks), skipping".format(extension_count)
                )
                return False

            self.print_error(
                "Extending MMR from", self.bootstrap_height,
                "to", target_height,
                "({} blocks)".format(extension_count)
            )

            # Read and extend headers one by one, verifying chain linkage
            prev_hash: Optional[str] = None
            actual_target = target_height

            for height in range(self.bootstrap_height + 1, target_height + 1):
                header = chain.read_header(height)
                if header is None:
                    self.print_error("Missing header at height", height)
                    if height - self.bootstrap_height >= MIN_EXTENSION_BLOCKS:
                        actual_target = height - 1
                        break
                    return False

                # Verify chain linkage
                if prev_hash is not None:
                    if header.get('prev_block_hash') != prev_hash:
                        self.print_error("Chain break at height", height)
                        return False

                # Compute header hash and extend MMR
                header_hex = blockchain.serialize_header(header)
                header_bytes = bytes.fromhex(header_hex)
                header_hash = Hash(header_bytes)

                self.accumulator.extend(header_hash)
                prev_hash = blockchain.hash_header(header)

                # Progress logging
                if (height - self.bootstrap_height) % 10000 == 0:
                    self.print_error("Extended to height", height)

            # Compute new root and save to config
            new_root = self.accumulator.get_root()
            new_root_hex = new_root[::-1].hex()  # Big-endian hex for storage

            self.config.set_key('verification_block_height', actual_target, save=False)
            self.config.set_key('verification_block_merkle_root', new_root_hex, save=True)

            self._extension_done = True
            self.print_error(
                "Saved checkpoint: height={} root={}...".format(
                    actual_target, new_root_hex[:16]
                )
            )
            return True

        except Exception as e:
            self.print_error("Extension failed:", repr(e))
            import traceback
            traceback.print_exc()
            return False

    def get_status(self) -> dict:
        """Return current status for debugging/UI."""
        return {
            'available': MMR_AVAILABLE,
            'bootstrapped': self._bootstrapped,
            'bootstrap_height': self.bootstrap_height,
            'leaf_count': self.accumulator.leaf_count if self.accumulator else None,
            'peak_count': self.accumulator.peak_count if self.accumulator else None,
            'extension_done': self._extension_done,
        }

    def prune_below_checkpoint(self) -> bool:
        """
        Replace headers below checkpoint with sparse storage.

        Called after extend_and_save() succeeds. Recreates the headers file
        with the region below checkpoint as a sparse hole, reclaiming disk space.
        Headers will be fetched on-demand with proofs when needed.

        Returns:
            True if pruning succeeded, False otherwise.
        """
        if not self._extension_done:
            self.print_error("Cannot prune - extension not done")
            return False

        if not self.config.get('verification_block_headers_auto_pruning', False):
            return False

        try:
            chain = self.network.blockchains.get(0)
            if chain is None:
                self.print_error("No main chain available")
                return False

            new_checkpoint = self.config.get('verification_block_height')
            if new_checkpoint is None or new_checkpoint <= 0:
                self.print_error("Invalid checkpoint height in config")
                return False

            filename = chain.path()
            if not os.path.exists(filename):
                self.print_error("Headers file does not exist")
                return False

            # Measure actual disk usage before pruning
            stat_before = os.stat(filename)
            blocks_before = getattr(stat_before, 'st_blocks', None)
            block_size = getattr(stat_before, 'st_blksize', 512)

            checkpoint_offset = new_checkpoint * blockchain.HEADER_SIZE

            with open(filename, 'rb') as f:
                f.seek(checkpoint_offset)
                headers_to_keep = f.read()

            if not headers_to_keep:
                self.print_error("No headers above checkpoint")
                return False

            kept_count = len(headers_to_keep) // blockchain.HEADER_SIZE
            self.print_error(
                "Pruning", new_checkpoint, "headers, keeping", kept_count
            )

            # Recreate as sparse file
            with open(filename, 'wb') as f:
                f.seek(checkpoint_offset - 1)
                f.write(b'\x00')
                f.seek(checkpoint_offset)
                f.write(headers_to_keep)
                f.flush()
                os.fsync(f.fileno())

            ensure_sparse_file(filename)

            # Report actual disk space reclaimed
            if blocks_before is not None:
                stat_after = os.stat(filename)
                blocks_after = getattr(stat_after, 'st_blocks', None)
                if blocks_after is not None:
                    # st_blocks is in 512-byte units
                    reclaimed_bytes = (blocks_before - blocks_after) * 512
                    if reclaimed_bytes > 0:
                        self.print_error(
                            "Reclaimed", reclaimed_bytes // 1024, "KB"
                        )

            return True

        except Exception as e:
            self.print_error("Pruning failed:", repr(e))
            import traceback
            traceback.print_exc()
            return False
