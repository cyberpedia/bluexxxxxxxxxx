from fastapi import Depends, HTTPException, Request, status

from app.services.store import store


def get_current_user(request: Request):
    token_payload = getattr(request.state, 'token_payload', None)
    if not token_payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Not authenticated')
    user = store.find_user_by_id(token_payload['sub'])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid user')
    return user


def require_capability(capability: str):
    def checker(user=Depends(get_current_user)):
        if capability not in user.capabilities:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Missing capability')
        return user

    return checker
