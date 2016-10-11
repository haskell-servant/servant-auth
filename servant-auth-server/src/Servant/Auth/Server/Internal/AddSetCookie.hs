{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PolyKinds                  #-}
{-# LANGUAGE UndecidableInstances       #-}
module Servant.Auth.Server.Internal.AddSetCookie where

import           Blaze.ByteString.Builder   (toByteString)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Base64     as BS64
import           Data.ByteString.Conversion (ToByteString (..))
import           Data.Monoid
import           Data.String                (IsString)
import qualified Data.Text.Encoding         as T
import           GHC.Generics               (Generic)
import           Servant
import           System.Entropy             (getEntropy)
import           Web.Cookie

-- What are we doing here? Well, the idea is to add headers to the response,
-- but the headers come from the authentication check. In order to do that, we
-- tweak a little the general theme of recursing down the API tree; this time,
-- we recurse down a variation of it that adds headers to all the endpoints.
-- This involves the usual type-level checks.
--
-- TODO: If the endpoints already have headers, this will not work as is.


type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (Verb method stat ctyps (Headers ls a))
     = Verb method stat ctyps (Headers ((Header "Set-Cookie" BSS) ': ls) a)
  AddSetCookieApi (Verb method stat ctyps a)
     = Verb method stat ctyps (Headers '[Header "Set-Cookie" BSS] a)


class AddSetCookie orig new where
  addSetCookie :: [SetCookie] -> orig -> new

instance {-# OVERLAPS #-} AddSetCookie oldb newb
  => AddSetCookie (a -> oldb) (a -> newb) where
  addSetCookie cookie oldfn = \val -> addSetCookie cookie $ oldfn val

instance {-# OVERLAPPABLE #-}
  ( Functor m
  , AddHeader "Set-Cookie" BSS old new
  ) => AddSetCookie (m old) (m new)  where
  addSetCookie cookie val
    -- What is happening here is sheer awfulness. Look the other way.
    = addHeader (BSS $ foldr1 go $ toByteString . renderSetCookie <$> cookie) <$> val
    where
      go new old = old <> "\r\nSet-Cookie: " <> new

instance {-# OVERLAPS #-}
  (AddSetCookie a a', AddSetCookie b b')
  => AddSetCookie (a :<|> b) (a' :<|> b') where
  addSetCookie cookie (a :<|> b) = addSetCookie cookie a :<|> addSetCookie cookie b


newtype BSS = BSS { getBSS :: BS.ByteString }
  deriving (Eq, Show, Read, Generic, IsString, Monoid)

instance ToHttpApiData BSS where
  toHeader = getBSS
  toUrlPiece = T.decodeUtf8 . getBSS

instance ToByteString BSS where
  builder (BSS x) = builder x

csrfCookie :: IO BS.ByteString
csrfCookie = BS64.encode <$> getEntropy 32
