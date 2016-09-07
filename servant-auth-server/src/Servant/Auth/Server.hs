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

  , AreAuths

  -- * Re-exports
  , module X
  , Default(def)
  ) where

import Servant.Auth.Server.Internal ()
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.Types
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth as X
import Data.Default.Class (Default(def))
