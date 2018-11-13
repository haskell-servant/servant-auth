{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
#if __GLASGOW_HASKELL__ == 800
{-# OPTIONS_GHC -fno-warn-redundant-constraints #-}
#endif
module Servant.Auth.Client.Internal where

import qualified Data.ByteString    as BS
import           Data.Monoid
import           Data.Proxy         (Proxy (..))
import           Data.String        (IsString)
import           GHC.Exts           (Constraint)
import           GHC.Generics       (Generic)
import           Servant.API        ((:>))
import           Servant.Auth

import           Servant.Client.Core
import           Data.Sequence ((<|))

-- | A compact JWT Token.
newtype Token = Token { getToken :: BS.ByteString }
  deriving (Eq, Show, Read, Generic, IsString)

type family HasJWT xs :: Constraint where
  HasJWT (JWT ': xs) = ()
  HasJWT (x ': xs)   = HasJWT xs
  HasJWT '[]         = JWTAuthNotEnabled

class JWTAuthNotEnabled

-- | @'HasJWT' auths@ is nominally a redundant constraint, but ensures we're not
-- trying to send a token to an API that doesn't accept them.
instance (HasJWT auths, HasClient m api) => HasClient m (Auth auths a :> api) where
  type Client m (Auth auths a :> api) = Token -> Client m api

  clientWithRoute m _ req (Token token)
    = clientWithRoute m (Proxy :: Proxy api)
    $ req { requestHeaders = ("Authorization", headerVal) <| requestHeaders req  }
      where
        headerVal = "Bearer " <> token

#if MIN_VERSION_servant_client_core(0,14,0)
  hoistClientMonad pm _ nt cl = hoistClientMonad pm (Proxy :: Proxy api) nt . cl
#endif
