module Servant.Auth.Server.Internal.FormLogin where

import           Control.Monad.Trans        (liftIO)
import           Data.Aeson                 (FromJSON, decode)
import qualified Data.ByteString.Lazy       as BL
import           GHC.Generics               (Generic)
import           Servant                    (ServantErr (..),
                                             err401, err403)
import           Network.Wai                (Request, requestBody)

import           Servant.Server.Internal.RoutingApplication
import           Servant.Auth.Server.Internal.Types

type family LoginData

newtype FormLoginCheck a =
  FormLoginCheck {runFormLoginCheck :: LoginData -> IO (AuthResult a)}
    deriving (Generic, Functor)

-- | Run and check basic authentication, returning the appropriate http error per
-- the spec.
runFormLogin :: (LoginData ~ form, FromJSON form)
             => Request -> FormLoginCheck a -> DelayedIO (AuthResult a)
runFormLogin req (FormLoginCheck fl) = do
  bdy <- liftIO $ requestBody req
  case decode $ BL.fromStrict bdy of
     Nothing -> plzAuthenticate
     Just f  -> do
       res <- liftIO $ fl f
       case res of
         BadPassword    -> plzAuthenticate
         NoSuchUser     -> plzAuthenticate
         Authenticated a -> return $ Authenticated a
  where plzAuthenticate = delayedFailFatal err401

