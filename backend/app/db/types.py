import uuid

from sqlalchemy.dialects.postgresql import UUID


def uuid_pk() -> UUID:
    return UUID(as_uuid=True)


def new_uuid() -> uuid.UUID:
    return uuid.uuid4()
