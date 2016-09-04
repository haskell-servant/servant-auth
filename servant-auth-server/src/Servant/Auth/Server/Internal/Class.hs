module Servant.Auth.Server.Internal.Class where

import Data.Proxy (Proxy(Proxy))
import Servant.Auth
import Data.Monoid

import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.JWT

-- | @IsAuth a ctx v@ indicates that @a@ is an auth type that expects @ctx@ to
-- be the in the Context and whose authentication check returns an @AuthCheck
-- v@.
class IsAuth a ctx v where
  runAuth :: proxy a -> ctx -> AuthCheck v

instance FromJWT usr => IsAuth Cookie CookieAuthConfig usr where
  runAuth _ = cookieAuthCheck

instance FromJWT usr => IsAuth JWT JWTAuthConfig usr where
  runAuth _ = jwtAuthCheck

-- * Helper

class AreAuths (as :: [*]) ctx v where
  runAuths :: proxy as -> ctx -> AuthCheck v

instance IsAuth a ctx v => AreAuths '[a] ctx v where
  runAuths _ = runAuth (Proxy :: Proxy a)

instance (IsAuth a ctx v, AreAuths as ctx v) => AreAuths (a ': as) ctx v where
  runAuths _ ctx = runAuth (Proxy :: Proxy a) ctx
                <> runAuths (Proxy :: Proxy as) ctx
