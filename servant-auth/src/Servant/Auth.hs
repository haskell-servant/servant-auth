{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Servant.Auth where

-- * Authentication

-- | @Auth [auth1, auth2] val :> api@ represents an API protected *either* by
-- @auth1@ or @auth2@
data Auth (auths :: [*]) val

-- ** Combinators

-- | A JSON Web Token (JWT) in the the Authorization header:
--
--    @Authorization: Bearer <token>@
--
-- Note that while the token is signed, it is not encrypted. Therefore do not
-- keep in it any information you would not like the client to know.
--
-- JWTs are described in IETF's <https://tools.ietf.org/html/rfc7519 RFC 7519>
data JWT

-- | A cookie. The content cookie itself is a JWT. Another cookie is also used,
-- the contents of which are expected to be send back to the server in a
-- header, for XSRF protection.
data Cookie


-- We could use 'servant''s BasicAuth, but then we don't get control over the
-- documentation, and we'd have to polykind everything. (Also, we don't
-- currently depend on servant!)
--
-- | Basic Auth.
data BasicAuth

-- | Login via a form.
data FormLogin form
