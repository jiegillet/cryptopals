{-# LANGUAGE OverloadedStrings #-}

import Network.HTTP
import Data.Time.Clock.POSIX
import Encodings
import Control.Monad (foldM, filterM)
import qualified Data.ByteString.Lazy as B

main = do
  let file = byteStringToHex ";user=admin;"
  hash <- findHash file
  putStrLn hash

findHash :: Hex -> IO Hex
findHash file = do
  let hexAlph = ['0'..'9']++['a'..'f']
      best h alph = do
        times <- mapM (\c -> fst <$> checkHash file (h++c:"#")) alph
        let hash = (\(_, c) -> h++[c]) $ maximum $ zip times alph
        print hash
        return hash
  initHash <- init <$> foldM best "" (replicate 39 hexAlph)
  [hash] <- filterM ((snd <$>) . checkHash file) $ map (\c-> initHash ++ [c]) hexAlph
  return hash

checkHash :: Hex -> Hex -> IO (POSIXTime, Bool)
checkHash file hash = do
  let pre = "http://localhost:8000/test?file="
      sep = "&signature="
      request = pre ++ file ++ sep ++ hash
  t0 <- getPOSIXTime
  response <- simpleHTTP (getRequest request)
  t1 <- getPOSIXTime
  (c,_,_) <- getResponseCode response
  return ((t1-t0), c==2)
