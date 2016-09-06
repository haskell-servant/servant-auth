module Servant.Auth.Server.Internal.AddSetCookie where

import Servant
import Web.Cookie
import qualified Data.ByteString as BS
import Blaze.ByteString.Builder (toByteString)

type family AddSetCookieApi a where
  AddSetCookieApi (a :> b) = a :> AddSetCookieApi b
  AddSetCookieApi (a :<|> b) = AddSetCookieApi a :<|> AddSetCookieApi b
  AddSetCookieApi (m a) = m (Headers '[Header "Set-Cookie" BS.ByteString] a)
  AddSetCookieApi (Headers ls a) = Headers ((Header "Set-Cookie" BS.ByteString) ': ls) a
  AddSetCookieApi a = Headers '[Header "Set-Cookie" BS.ByteString] a


type family AddedSetCookie a where
  AddedSetCookie (a -> b) = a -> AddedSetCookie b
  AddedSetCookie (t (m old)) = t (AddedSetCookie (m old))
  AddedSetCookie (m old) = m (AddedSetCookie old)
  AddedSetCookie old = Headers '[Header "Set-Cookie" BS.ByteString] old

class AddSetCookie orig where
  addSetCookie :: SetCookie -> orig -> AddedSetCookie orig

instance {-# OVERLAPS #-} AddSetCookie oldb => AddSetCookie (a -> oldb) where
  addSetCookie cookie oldfn = \val -> addSetCookie cookie $ oldfn val

instance (Functor m, AddSetCookie a) => AddSetCookie (m a) where
  addSetCookie cookie v = addSetCookie cookie <$> v

instance {-# OVERLAPPABLE #-}
  (AddedSetCookie old ~ Headers '[Header "Set-Cookie" BS.ByteString] old)
       => AddSetCookie old where
  addSetCookie cookie val
    = addHeader (toByteString $ renderSetCookie cookie) val :: Headers '[Header "Set-Cookie" BS.ByteString] old
