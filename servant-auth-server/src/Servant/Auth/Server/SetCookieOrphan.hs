{-# OPTIONS_GHC -fno-warn-orphans #-}
module Servant.Auth.Server.SetCookieOrphan () where

import Blaze.ByteString.Builder (toByteString)
import Data.Text.Encoding       (decodeUtf8, encodeUtf8)
import Web.Cookie               (SetCookie, parseSetCookie, renderSetCookie)
import Web.HttpApiData          (FromHttpApiData (..), ToHttpApiData (..))
import Data.ByteString.Conversion (ToByteString(..))

instance FromHttpApiData SetCookie where
    parseUrlPiece = parseHeader . encodeUtf8
    parseHeader = Right . parseSetCookie

instance ToHttpApiData SetCookie where
    toUrlPiece = decodeUtf8 . toHeader
    toHeader = toByteString . renderSetCookie

instance ToByteString SetCookie where
    builder = renderSetCookie
