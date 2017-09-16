ELECTRUM_VERSION = '3.0'     # version of the client package
PROTOCOL_VERSION = '1.1'     # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet
SEED_PREFIX_SW   = '100'     # Segwit wallet


def seed_prefix(seed_type):
    if seed_type == 'standard':
        return SEED_PREFIX
    elif seed_type == 'segwit':
        return SEED_PREFIX_SW
