module Servant.Auth where

import Data.Reflection (Reifies(reflect))
import GHC.TypeLits (Symbol)
import GHC.Generics (Generic)

-- * Authentication

-- | @Auth [auth1, auth2] val :> api@ represents an API protected *either* by
-- @auth1@ or @auth2@
data Auth (auths :: [*]) val

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
-- header, for CSRF protection.
data Cookie

-- | Login via a form.
data FormLogin form

-- * Setting cookies

data SetCookie (cookieName :: Symbol) (isSecure :: IsSecure)
               (isHttpOnly :: IsHttpOnly) (value :: *)

-- 'servant' already has one of these, just without constructors
data IsSecure = Secure | NotSecure
  deriving (Eq, Show, Read, Generic, Ord)

instance Reifies 'Secure IsSecure where
  reflect _ = Secure

instance Reifies 'NotSecure IsSecure where
  reflect _ = NotSecure

data IsHttpOnly = HttpOnly | NotHttpOnly
  deriving (Eq, Show, Read, Generic, Ord)

instance Reifies 'HttpOnly IsHttpOnly where
  reflect _ = HttpOnly

instance Reifies 'NotHttpOnly IsHttpOnly where
  reflect _ = NotHttpOnly
