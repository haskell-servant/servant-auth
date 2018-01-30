module Servant.Auth.Server.Internal.BasicAuth where

import qualified Data.ByteString                   as BS
import           Servant                           (BasicAuthData (..),
                                                    ServantErr (..), err401)
import           Servant.Server.Internal.BasicAuth (decodeBAHdr,
                                                    mkBAChallengerHdr)


import Servant.Auth.Server.Internal.Types

-- | A 'ServantErr' that asks the client to authenticate via Basic
-- Authentication, should be invoked by an application whenever
-- appropriate. The argument is the realm.
wwwAuthenticatedErr :: BS.ByteString -> ServantErr
wwwAuthenticatedErr realm = err401 { errHeaders = [mkBAChallengerHdr realm] }

type family BasicAuthCfg

class FromBasicAuthData a where
  -- | Whether the username exists and the password is correct.
  -- Note that, rather than passing a 'Pass' to the function, we pass a
  -- function that checks an 'EncryptedPass'. This is to make sure you don't
  -- accidentally do something untoward with the password, like store it.
  fromBasicAuthData :: BasicAuthData -> BasicAuthCfg -> IO (AuthResult a)

basicAuthCheck :: FromBasicAuthData usr => BasicAuthCfg -> AuthCheck usr
basicAuthCheck cfg = AuthCheck $ \req -> case decodeBAHdr req of
  Nothing -> return Indefinite
  Just baData -> fromBasicAuthData baData cfg
