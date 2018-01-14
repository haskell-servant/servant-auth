module Servant.Auth.Server.Internal.JWT where

import           Control.Lens
import           Control.Monad.Except
import           Control.Monad.Reader
import qualified Crypto.JOSE          as Jose
import qualified Crypto.JWT           as Jose
import           Data.Aeson           (FromJSON, Result (..), ToJSON, fromJSON,
                                       toJSON)
import qualified Data.ByteString.Lazy as BSL
import qualified Data.HashMap.Strict  as HM
import           Data.Text            (Text)
import           Data.Time            (UTCTime)
import           GHC.Generics         (Generic)
import           Network.Wai          (requestHeaders)
import           Web.HttpApiData      (parseHeader)

import Servant.Auth
import Servant.Auth.Server.Internal.ConfigTypes
import Servant.Auth.Server.Internal.Types

data JWTDecodeError
  = JWTError Jose.JWTError
  | JWTMissingDATClaim
  | JWTJSONError String
  | JWTOtherError Text
  deriving (Eq, Generic, Show)

data JWTAuthError
  = JWTAuthHeaderMissing
  | JWTParseHeaderFailed Text
  | JWTDecodeError JWTDecodeError
  deriving (Eq, Generic, Show)


-- This should probably also be from ClaimSet
--
-- | How to decode data from a JWT.
--
-- The default implementation assumes the data is stored in the unregistered
-- @dat@ claim, and uses the @FromJSON@ instance to decode value from there.
class FromJWT a where
  decodeJWT :: Jose.ClaimsSet -> Either JWTDecodeError a
  default decodeJWT :: FromJSON a => Jose.ClaimsSet -> Either JWTDecodeError a
  decodeJWT m = case HM.lookup "dat" (m ^. Jose.unregisteredClaims) of
    Nothing -> Left JWTMissingDATClaim
    Just v  -> case fromJSON v of
      Error e -> Left $ JWTJSONError e
      Success a -> Right a

-- | How to encode data from a JWT.
--
-- The default implementation stores data in the unregistered @dat@ claim, and
-- uses the type's @ToJSON@ instance to encode the data.
class ToJWT a where
  encodeJWT :: a -> Jose.ClaimsSet
  default encodeJWT :: ToJSON a => a -> Jose.ClaimsSet
  encodeJWT a = Jose.addClaim "dat" (toJSON a) Jose.emptyClaimsSet

-- | A JWT @AuthCheck@. You likely won't need to use this directly unless you
-- are protecting a @Raw@ endpoint.
jwtAuthCheck :: FromJWT usr => JWTSettings -> AuthCheck JWTAuthError usr
jwtAuthCheck config = do
  req <- ask
  case lookup "Authorization" $ requestHeaders req of
    Nothing -> failWith JWTAuthHeaderMissing
    Just authHdr -> case parseHeader authHdr of
      Left err -> failWith $ JWTParseHeaderFailed err
      Right jwt -> do
        result <- liftIO $ verifyAndDecodeJWT config jwt
        either (failWith . JWTDecodeError) pure result

verifyAndDecodeJWT :: FromJWT usr
  => JWTSettings -> Token usr -> IO (Either JWTDecodeError usr)
verifyAndDecodeJWT config (Token token) = do
  verifiedJWT <- liftIO $ runExceptT $ do
    unverifiedJWT <- Jose.decodeCompact $ BSL.fromStrict token
    Jose.verifyClaims (jwtSettingsToJwtValidationSettings config)
      (key config) unverifiedJWT
  pure $ either (Left . JWTError) decodeJWT verifiedJWT


-- | Creates a JWT containing the specified data. The data is stored in the
-- @dat@ claim. The 'Maybe UTCTime' argument indicates the time at which the
-- token expires.
makeJWT :: (Jose.MonadRandom m, ToJWT a)
  => a -> JWTSettings -> Maybe UTCTime -> m (Either Jose.Error (Token a))
makeJWT v cfg expiry = runExceptT $ do
  alg <- Jose.bestJWSAlg $ key cfg
  let header = Jose.newJWSHeader ((), alg)
  ejwt <- Jose.signClaims (key cfg) header (addExp $ encodeJWT v)
  return $ Token $ BSL.toStrict $ Jose.encodeCompact ejwt
  where
   addExp claims = case expiry of
     Nothing -> claims
     Just e  -> claims & Jose.claimExp .~ Just (Jose.NumericDate e)
