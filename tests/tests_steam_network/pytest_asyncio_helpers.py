"""
Helper functions to handle different pytest-asyncio versions.

This module provides utility functions to reduce repetition when handling
both old and new pytest-asyncio versions in test files.
"""


async def resolve_async_fixture(fixture):
    """
    Resolve async fixture handling both old and new pytest-asyncio versions.
    
    This function uses a try/except approach which is more reliable than
    checking for attributes, as it directly tests if the fixture needs awaiting.
    
    Args:
        fixture: The fixture that may be a coroutine or resolved instance
    
    Returns:
        The resolved fixture instance
    """
    try:
        # Try to await it (older pytest-asyncio)
        return await fixture
    except TypeError:
        # If that fails, it's already resolved (newer pytest-asyncio)
        return fixture
