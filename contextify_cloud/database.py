"""Database connection and session management."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from contextify_cloud.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.log_level == "debug",
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    # Pull page locking requires a fresh snapshot after acquiring its table lock.
    isolation_level="READ COMMITTED",
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Dependency that provides a database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
