"""Reference durable :class:`~tx402.ledger.SpendStore` adapters (SPEC §12).

Currently ships the Redis backend (``tx402.stores.redis``): ``RedisSpendStore`` (sync) and
``AsyncRedisSpendStore`` (async, over ``redis.asyncio``). Import from the submodule, which
requires the ``redis`` extra (``pip install tx402[redis]``).
"""
