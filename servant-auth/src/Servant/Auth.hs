module Servant.Auth where

-- | @Auth [auth1, auth2] val :> api@ represents an API protected *either* by
-- @auth1@ or @auth2@
data Auth (auths :: [*]) val

data JWT
data Cookie
data Login
