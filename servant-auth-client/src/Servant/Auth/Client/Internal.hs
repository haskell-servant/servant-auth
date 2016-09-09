{-# LANGUAGE CPP                        #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE UndecidableInstances       #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
#if MIN_VERSION_base(4,9,0)
{-# OPTIONS_GHC -fno-warn-redundant-constraints #-}
#endif
module Servant.Auth.Client.Internal where

import qualified Data.ByteString    as BS
import           Data.Monoid
import           Data.Proxy         (Proxy (..))
import           Data.String        (IsString)
import qualified Data.Text.Encoding as T
import           GHC.Exts           (Constraint)
import           GHC.Generics       (Generic)
import           Servant.API        ((:>))
import           Servant.Auth
import           Servant.Client
import           Servant.Common.Req (Req (..))

-- | A compact JWT Token.
newtype Token = Token { getToken :: BS.ByteString }
  deriving (Eq, Show, Read, Generic, IsString)


    -- HasJWT auths is nominally a redundant constraint, but ensures we're not
    -- trying to send a token to an API that doesn't accept them.
instance (HasJWT auths, HasClient api) => HasClient (Auth auths a :> api) where

  type Client (Auth auths a :> api) = Token -> Client api

  clientWithRoute _ req (Token token)
   = clientWithRoute (Proxy :: Proxy api)
   $ req { headers = ("Authorization", headerVal):headers req  }
     where
       -- 'servant-client' shouldn't be using a Text here; it should be using a
       -- ByteString.
       headerVal = "Bearer " <> T.decodeLatin1 token

type family HasJWT xs :: Constraint where
  HasJWT (JWT ': xs) = ()
  HasJWT (x ': xs)   = HasJWT xs
  HasJWT '[]         = JWTAuthNotEnabled

class JWTAuthNotEnabled
