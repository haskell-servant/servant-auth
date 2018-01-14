{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilyDependencies #-}
{-# LANGUAGE UndecidableInstances #-}
module Servant.Auth.Server.Internal.Class where

import Data.Proxy
import GHC.Generics (Generic)
import Network.Wai (Request)
import Servant hiding (BasicAuth)

import Servant.Auth
import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.BasicAuth
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.JWT

-- | The result of running the auths 'as'
data AuthResult auths v
  = Authenticated v
  | AuthFailed (ErrorList (AuthsToErrors auths))
  deriving (Generic, Functor, Traversable, Foldable)

deriving instance (Eq v, Eq (ErrorList (AuthsToErrors auths)))
  => Eq (AuthResult auths v)
deriving instance (Show v, Show (ErrorList (AuthsToErrors auths)))
  => Show (AuthResult auths v)


-- | Open type family
type family AuthsToErrors (auths :: [*]) = (errs :: [*]) | errs -> auths where
  AuthsToErrors '[] = '[]
  AuthsToErrors (a ': auths) = AuthError a ': AuthsToErrors auths

-- | HList as a GADT. Named differently to prevent clash with servant's HList
data ErrorList (as :: [*]) where
  ENil :: ErrorList '[]
  ECons :: a -> ErrorList as -> ErrorList (a ': as)

instance Show (ErrorList '[]) where
  show ENil = "ENil"
instance (Show a, Show (ErrorList as)) => Show (ErrorList (a ': as)) where
  show (ECons a as) = show a ++ " ': " ++ show as

instance Eq (ErrorList '[]) where
  ENil == ENil = True
instance (Eq a, Eq (ErrorList as)) => Eq (ErrorList (a ': as)) where
  ECons a as == ECons a' as' = a == a' && as == as'

-- | @IsAuth a ctx v@ indicates that @a@ is an auth type that expects all
-- elements of @ctx@ to be the in the Context and whose authentication check
-- returns an @AuthCheck v@.
class IsAuth a v where
  type family AuthError a = (err :: *) | err -> a
  type family AuthArgs a :: [*]
  runAuth :: proxy a -> proxy v
          -> Unapp (AuthArgs a) (AuthCheck (AuthError a) v)

instance FromJWT usr => IsAuth Cookie usr where
  type AuthArgs Cookie = '[CookieSettings, JWTSettings]
  type AuthError Cookie = CookieAuthError
  runAuth _ _ = cookieAuthCheck

instance FromJWT usr => IsAuth JWT usr where
  type AuthArgs JWT = '[JWTSettings]
  type AuthError JWT = JWTAuthError
  runAuth _ _ = jwtAuthCheck

instance FromBasicAuthData usr => IsAuth BasicAuth usr where
  type AuthArgs BasicAuth = '[BasicAuthCfg]
  type AuthError BasicAuth = BasicAuthError
  runAuth _ _ = basicAuthCheck

-- * Helper

-- | Helper for running many auth checks
class AreAuths (as :: [*]) (ctxs :: [*]) v where
  runAuths :: proxy as -> Context ctxs -> Request
           -> IO (AuthResult as v)

instance  AreAuths '[] ctxs v where
  runAuths _ _ _ = pure $ AuthFailed ENil

-- | Convenience function
addFailed :: AuthError e -> AuthResult es a -> AuthResult (e ': es) a
addFailed e (AuthFailed es) = AuthFailed $ ECons e es
addFailed _ (Authenticated a) = Authenticated a

instance ( AuthCheck (AuthError a) v ~ App (AuthArgs a) (Unapp (AuthArgs a) (AuthCheck (AuthError a) v))
         , IsAuth a v
         , AreAuths as ctxs v
         , AppCtx ctxs (AuthArgs a) (Unapp (AuthArgs a) (AuthCheck (AuthError a) v))
         ) => AreAuths (a ': as) ctxs v where
  runAuths _ ctxs req = runAuthCheck go req >>= \x -> case x of
    Left e -> addFailed e <$> runAuths (Proxy :: Proxy as) ctxs req
    Right a -> pure $ Authenticated a
    where
      go = appCtx (Proxy :: Proxy (AuthArgs a))
                  ctxs
                  (runAuth (Proxy :: Proxy a) (Proxy :: Proxy v))

type family Unapp ls res where
  Unapp '[] res = res
  Unapp (arg1 ': rest) res = arg1 -> Unapp rest res

type family App ls res where
  App '[] res = res
  App (arg1 ': rest) (arg1 -> res) = App rest res

-- | @AppCtx@ applies the function @res@ to the arguments in @ls@ by taking the
-- values from the Context provided.
class AppCtx ctx ls res where
  appCtx :: proxy ls -> Context ctx -> res -> App ls res

instance ( HasContextEntry ctxs ctx
         , AppCtx ctxs rest res
         ) => AppCtx ctxs (ctx ': rest) (ctx -> res) where
  appCtx _ ctx fn = appCtx (Proxy :: Proxy rest) ctx $ fn $ getContextEntry ctx

instance AppCtx ctx '[] res where
  appCtx _ _ r = r
