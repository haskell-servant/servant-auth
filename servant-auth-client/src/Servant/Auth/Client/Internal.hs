{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
#if __GLASGOW_HASKELL__ == 800
{-# OPTIONS_GHC -fno-warn-redundant-constraints #-}
#endif
module Servant.Auth.Client.Internal where

import           Data.Proxy         (Proxy (..))
import           GHC.Exts           (Constraint)
import           Servant.API        ((:>))
import           Servant.Auth
import           Web.HttpApiData    (toHeader)

#ifdef HAS_CLIENT_CORE
import           Servant.Client.Core
import           Data.Sequence ((<|))
#else
import           Servant.Client
import           Servant.Common.Req (Req (..))
import qualified Data.Text.Encoding as T
#endif

type family HasJWT xs :: Constraint where
  HasJWT (JWT ': xs) = ()
  HasJWT (x ': xs)   = HasJWT xs
  HasJWT '[]         = JWTAuthNotEnabled

class JWTAuthNotEnabled

-- | @'HasJWT' auths@ is nominally a redundant constraint, but ensures we're not
-- trying to send a token to an API that doesn't accept them.
#ifdef HAS_CLIENT_CORE
instance (HasJWT auths, HasClient m api) => HasClient m (Auth auths a :> api) where
  type Client m (Auth auths a :> api) = Token a -> Client m api

  clientWithRoute m _ req token
    = clientWithRoute m (Proxy :: Proxy api)
    $ req { requestHeaders = ("Authorization", toHeader token) <| requestHeaders req  }
#else
instance (HasJWT auths, HasClient api) => HasClient (Auth auths a :> api) where
  type Client (Auth auths a :> api) = Token a -> Client api

  clientWithRoute _ req token
    = clientWithRoute (Proxy :: Proxy api)
    $ req { headers = ("Authorization", headerVal):headers req  }
      where
        -- 'servant-client' shouldn't be using a Text here; it should be using a
        -- ByteString.
        headerVal = T.decodeLatin1 $ toHeader token
#endif
