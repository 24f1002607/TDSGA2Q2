"""
OAuth 2.0 / OIDC Token Verification Service
POST /verify  -> validates an RS256 JWT and returns a structured result.
"""

import jwt  # this is the "PyJWT" library
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Your assigned values. These are the "expected" answers the token must match.
# ---------------------------------------------------------------------------
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-727n01d5.apps.exam.local"

# The IdP's public key. We use it to check the signature seal.
# The triple-quoted string keeps the exact formatting, including line breaks.
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI()


# The shape of the incoming request body: {"token": "<JWT string>"}
class VerifyRequest(BaseModel):
    token: str


@app.post("/verify")
def verify(body: VerifyRequest):
    try:
        # jwt.decode does ALL FOUR checks for us:
        #   - signature (using PUBLIC_KEY + algorithms=["RS256"])
        #   - audience  (must equal AUDIENCE)
        #   - issuer    (must equal ISSUER)
        #   - expiry    (exp must be in the future) -- checked automatically
        # If anything fails, it raises an exception, which we catch below.
        claims = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )

        # If we got here, the token is valid. Echo the claims back.
        return {
            "valid": True,
            "email": claims.get("email"),
            "sub": claims.get("sub"),
            "aud": claims.get("aud"),
        }

    except Exception:
        # Any failure -> 401 with {"valid": false}
        return JSONResponse(status_code=401, content={"valid": False})


# A simple health check so you can confirm the app is alive in a browser.
@app.get("/")
def root():
    return {"status": "ok"}
