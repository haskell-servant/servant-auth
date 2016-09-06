module Servant.Auth.Server
  (
    AuthResult(..)

  -- * JWT
  , FromJWT(..)
  , ToJWT(..)
  , JWTAuthConfig(..)
  , defaultJWTAuthConfig

  -- * Cookie
  , CookieAuthConfig(..)
  , defaultCookieAuthConfig

  , AreAuths

  -- * Re-exports
  , module X
  ) where

import Servant.Auth.Server.Internal ()
import Servant.Auth.Server.Internal.Class
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Cookie
import Servant.Auth.Server.Internal.Types
import Servant.Auth as X

