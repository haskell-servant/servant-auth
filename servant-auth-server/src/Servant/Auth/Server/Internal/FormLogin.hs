module Servant.Auth.Server.Internal.FormLogin where

import           Data.Aeson                 (FromJSON, decode)
import qualified Data.ByteString.Lazy       as BL
import           Network.Wai                (requestBody)

import           Servant.Auth.Server.Internal.Types

type family FormLoginData

class FromFormLoginData a where
  -- | Represents an object that can be constructed from FormLoginData
  -- inside the IO monad with possible failure.
  fromLoginData :: FormLoginData -> IO (AuthResult a)

-- | An AuthCheck for requests containing LoginFormData in the body.
formLoginCheck :: (FormLoginData ~ form,
                   FromJSON form,
                   FromFormLoginData a
                  ) => AuthCheck a
formLoginCheck = AuthCheck $ \req -> do
  bdy <- requestBody req
  case decode $ BL.fromStrict bdy of
     Nothing -> return Indefinite
     Just f  -> fromLoginData f
