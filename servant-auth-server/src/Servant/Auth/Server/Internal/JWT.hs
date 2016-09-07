module Servant.Auth.Server.Internal.JWT where

import           Control.Lens
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import           Crypto.Util          (constTimeEq)
import           Data.Aeson           (FromJSON, Result (..), ToJSON, fromJSON,
                                       toJSON)
import qualified Data.ByteString      as BS
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict  as HM
import qualified Data.Text            as T
import           Data.Time            (UTCTime)
import           Network.Wai          (requestHeaders)

import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.Types

-- This should probably also be from ClaimSet
class FromJWT a where
  decodeJWT :: Jose.JWT -> Either T.Text a
  default decodeJWT :: FromJSON a => Jose.JWT -> Either T.Text a
  decodeJWT m = case HM.lookup "dat" (Jose._unregisteredClaims $ Jose.jwtClaimsSet m ) of
    Nothing -> Left "Missing 'dat' claim"
    Just v  -> case fromJSON v of
      Error e -> Left $ T.pack e
      Success a -> Right a

class ToJWT a where
  encodeJWT :: a -> Jose.ClaimsSet
  default encodeJWT :: ToJSON a => a -> Jose.ClaimsSet
  encodeJWT a = Jose.addClaim "dat" (toJSON a) $ Jose.emptyClaimsSet

jwtAuthCheck :: FromJWT usr => JWTSettings -> AuthCheck usr
jwtAuthCheck config = do
  req <- ask
  token <- maybe mempty return $ do
    authHdr <- lookup "Authorization" $ requestHeaders req
    let bearer = "Bearer "
        (mbearer, rest) = BS.splitAt (BS.length bearer) authHdr
    guard (mbearer `constTimeEq` bearer)
    return rest
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.validateJWSJWT (jwtSettingsToJwtValidationSettings config)
                        (key config)
                        unverifiedJWT
    return unverifiedJWT
  case verifiedJWT of
    Left (_ :: Jose.JWTError) -> mzero
    Right v -> case decodeJWT v of
      Left _ -> mzero
      Right v' -> return v'



-- | Creates a JWT containing the specified data. The data is stored in the
-- @dat@ claim. The token will be valid for the period specified.
makeJWT :: ToJWT a
  => a -> JWTSettings -> Maybe UTCTime -> ExceptT Jose.Error IO BSL.ByteString
makeJWT v cfg expiry = ExceptT $ do
  ejwt <- Jose.createJWSJWT (key cfg)
                            (Jose.newJWSHeader (Jose.Protected, Jose.HS256))
                            (addExp $ encodeJWT v)

  return $ ejwt >>= Jose.encodeCompact
  where
   addExp claims = case expiry of
     Nothing -> claims
     Just e  -> claims & Jose.claimExp .~ Just (Jose.NumericDate e)
  {-return $ Token . BSL.toStrict <$> (ejwt >>= Jose.encodeCompact)-}
  {-where-}
   {-ejwt' = Jose.createJWSJWT-}
                    {-(key cfg)-}
                    {-(Jose.newJWSHeader (Jose.Protected, Jose.HS256))-}
                    {-(addExp Jose.emptyClaimsSet-}
                       {-& Jose.unregisteredClaims .~ encodeJWTData dat)-}

