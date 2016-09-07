module Servant.Auth.Server
  (
    AuthResult(..)

  -- * JWT
  , FromJWT(..)
  , ToJWT(..)
  , JWTSettings(..)
  , defaultJWTSettings

  -- * Cookie
  , CookieSettings(..)
  , defaultCookieSettings
  , IsSecure(..)

  , AreAuths

  , generateKey
  , makeJWT

  -- * Re-exports
  , module X
  , Default(def)
  ) where

import Servant.Auth.Server.Internal ()
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth as X
import Data.Default.Class (Default(def))

import Crypto.JOSE as Jose

-- | Generate a key suitable for use with 'defaultConfig'.
generateKey :: IO Jose.JWK
generateKey = Jose.genJWK $ Jose.OctGenParam 256
