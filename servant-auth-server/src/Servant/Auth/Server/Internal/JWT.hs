module Servant.Auth.Server.Internal.JWT where

import qualified Crypto.JWT                         as Jose
import           Servant.Auth.Server.Internal.Types

class FromJWT a where
  decodeJWT :: Jose.JWT -> a

class ToJWT a where
  encodeJWT :: a -> Jose.JWT

jwtAuthCheck :: AuthCheck usr
jwtAuthCheck = undefined
