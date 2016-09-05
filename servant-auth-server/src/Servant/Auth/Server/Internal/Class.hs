{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.Class where

import Servant.Auth
import Data.Monoid
import Servant

import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.JWT

-- | @IsAuth a ctx v@ indicates that @a@ is an auth type that expects @ctx@ to
-- be the in the Context and whose authentication check returns an @AuthCheck
-- v@.
class IsAuth a ctx v | a v -> ctx where
  runAuth :: proxy a -> ctx -> AuthCheck v

instance FromJWT usr => IsAuth Cookie CookieAuthConfig usr where
  runAuth _ = cookieAuthCheck

instance FromJWT usr => IsAuth JWT JWTAuthConfig usr where
  runAuth _ = jwtAuthCheck

-- * Helper

class AreAuths (as :: [*]) (ctxs :: [*]) v where
  runAuths :: proxy as -> Context ctxs -> AuthCheck v

instance  AreAuths '[] ctxs v where
  runAuths _ _ = mempty

instance ( IsAuth a ctx v, HasContextEntry ctxs ctx, AreAuths as ctxs v
         ) => AreAuths (a ': as) ctxs v where
  runAuths _ ctxs = runAuth (Proxy :: Proxy a) (getContextEntry ctxs)
                <> runAuths (Proxy :: Proxy as) ctxs
