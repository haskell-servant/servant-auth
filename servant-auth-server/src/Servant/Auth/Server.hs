module Servant.Auth.Server
  (
    AuthResult(..)

  -- * JWT
  , FromJWT(..)
  , ToJWT(..)
  , JWTAuthConfig(..)
  , defaultJWTAuthConfig

  -- * Re-exports
  , module X
  ) where

import Servant.Auth.Server.Internal ()
import Servant.Auth.Server.Internal.JWT
import Servant.Auth.Server.Internal.Types
import Servant.Auth as X

