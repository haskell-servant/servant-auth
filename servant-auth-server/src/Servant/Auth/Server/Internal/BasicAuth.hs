module Servant.Auth.Server.Internal.BasicAuth where

import qualified Data.ByteString                   as BS
import           Data.Text                         (Text)
import           GHC.Generics                      (Generic)
import           Servant                           (BasicAuthData (..),
                                                    ServantErr (..), err401)
import           Servant.Server.Internal.BasicAuth (decodeBAHdr,
                                                    mkBAChallengerHdr)


import Servant.Auth.Server.Internal.Types

-- | A 'ServantErr' that asks the client to authenticated via Basic
-- Authentication. The argument is the realm.
wwwAuthenticatedErr :: BS.ByteString -> ServantErr
wwwAuthenticatedErr realm = err401 { errHeaders = [mkBAChallengerHdr realm] }

type family BasicAuthCfg

class FromBasicAuthData a where
  -- | Whether the username exists and the password is correct.
  -- Note that, rather than passing a 'Pass' to the function, we pass a
  -- function that checks an 'EncryptedPass'. This is to make sure you don't
  -- accidentally do something untoward with the password, like store it.
  fromBasicAuthData :: BasicAuthData -> BasicAuthCfg -> IO (Either BasicAuthError a)

data BasicAuthError
  = BasicAuthBadPassword
  | BasicAuthNoSuchUser
  | BasicAuthDecodingFailed
  | BasicAuthOtherError Text
  deriving (Eq, Generic, Show)

basicAuthCheck :: FromBasicAuthData usr => BasicAuthCfg -> AuthCheck BasicAuthError usr
basicAuthCheck cfg = AuthCheck $ \req -> case decodeBAHdr req of
  Nothing -> pure $ Left BasicAuthDecodingFailed
  Just baData -> fromBasicAuthData baData cfg
