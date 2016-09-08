module Servant.Auth.Server.Internal.BasicAuth where

import           Crypto.Scrypt
import qualified Data.ByteString                   as BS
import           Servant                           (BasicAuthData (..),
                                                    ServantErr (..), err401)
import           Servant.Server.Internal.BasicAuth (decodeBAHdr,
                                                    mkBAChallengerHdr)

import qualified Data.Text.Encoding as T

import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.Types

-- | Utility function that hashes a password according to the settings in
-- 'BasicAuthSettings'.
hashPassword :: BasicAuthSettings usr -> Pass -> IO EncryptedPass
hashPassword settings pwd = do
  salt <- genSalt settings
  return $ encryptPass (scryptOptions settings) salt pwd

-- | A 'ServantErr' that asks the client to authenticated via Basic
-- Authentication. The argument is the realm.
wwwAuthenticatedErr :: BS.ByteString -> ServantErr
wwwAuthenticatedErr realm = err401 { errHeaders = [mkBAChallengerHdr realm] }

basicAuthCheck :: BasicAuthSettings usr -> AuthCheck usr
basicAuthCheck settings = AuthCheck $ \req -> do
  case decodeBAHdr req of
    Nothing -> return Indefinite
    Just (BasicAuthData usr pwd) ->
      basicAuthCheckPwd settings (Username $ T.decodeUtf8 usr) checkPass
      where
        checkPass phash = if verifyPass' (Pass pwd) phash
           then PasswordCorrect
           else PasswordIncorrect
