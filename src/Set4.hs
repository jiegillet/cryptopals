{-# LANGUAGE OverloadedStrings #-}

import           Encodings
import           AES128
import           Set2
import           Hashes
import qualified Data.ByteString.Lazy as B
import qualified Data.ByteString.Lazy.Char8 as C
import           System.Random
import           Control.Exception
import           Control.Monad (filterM, foldM, (=<<))
import           Test.QuickCheck (quickCheck)
import           Data.List (sortOn)
import           Data.Bits
import           Network.HTTP (simpleHTTP, getRequest, getResponseCode)
import           Data.Time.Clock.POSIX
import           Data.Map (Map, (!))
import qualified Data.Map as M

-- Ex 25

edit :: ByteString -> ByteString -> Int64 -> ByteString -> ByteString
edit cypher key offset newtext
  | B.null newtext           = cypher
  | B.null cypher            = encodeAES128CTR key (0, 0) newtext
  | offset < 0               = edit cypher key 0 newtext
  | offset > B.length cypher = edit cypher key (B.length cypher) newtext
  | otherwise                = B.concat [pre, change core, post]
  where
  (n, off) = quotRem offset 16
  (pre, tmp) = B.splitAt (16 * n) cypher
  (core, post) = B.splitAt (off + B.length newtext) tmp
  change = encodeAES128CTR key (0, fromIntegral n) .
           replace off newtext .
           decodeAES128CTR key (0, fromIntegral n)

replace :: Int64 -> ByteString -> ByteString -> ByteString
replace off new old = let (pre, mid) = B.splitAt off old
                          (_, post) = B.splitAt (B.length new) mid
                      in B.concat [pre, new, post]

prop_edit :: String -> String -> Int64 -> Bool
prop_edit txt' new' offset = replace offset new txt == edited
  where txt = C.pack txt'
        new = C.pack new'
        key = "YELLOW SUBMARINE"
        edited = decodeAES128CTR key (0, 0) $
                 (\cypher -> edit cypher key offset new) $
                 encodeAES128CTR key (0, 0) txt

ex25 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  r <- base64ToByteString . filter (/= '\n') <$> readFile "../doc/25.txt"
  let plain = decodeAES128ECB "YELLOW SUBMARINE" r
      seed = (0, 0)
      cypher = decodeAES128CTR key seed plain
      editAPI cypher offset newtext = edit cypher key offset newtext
  putStrLn $ C.unpack $  editAPI cypher 0 cypher

-- Ex 26

addAdmin :: (ByteString -> ByteString) -> (ByteString -> Bool) -> ByteString
addAdmin encoder check = cyphertext
  where offset = let a = encoder "a"
                     b = encoder "b"
                 in fromIntegral $ length $ takeWhile id $ B.zipWith (==) a b
        msg = encoder "_admin|true_"
        xorMe = xorB "_admin|true_" ";admin=true;"
        (pre, tmp) = B.splitAt offset msg
        (core, post) = B.splitAt 12 tmp
        cyphertext = B.concat [pre, xorB xorMe core, post]

escape :: ByteString -> ByteString
escape = B.filter (not . flip B.elem ";=")

ex26 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let prefix  = "comment1=cooking%20MCs;userdata="
      postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
      encoder = encodeAES128CTR key (0, 0) . (\x -> B.concat [prefix, x, postfix]) . escape
      decoder = decodeAES128CTR key (0, 0)

  let cyphertext = addAdmin encoder (isAdmin decoder)
  print $ decoder cyphertext
  print $ isAdmin decoder cyphertext

-- Ex 27

asciiCompliant :: (ByteString -> ByteString) -> ByteString -> Bool
asciiCompliant decoder cypher
  | B.all (<128) plain = True
  | otherwise          = throw (ASCIIComplianceException plain)
  where plain = decoder cypher

findKey :: (ByteString -> Bool) -> ByteString -> IO ByteString
findKey check cypher = do
  let oops (ASCIIComplianceException e) = return e
      (c1:_:_:rest) = chunksOf 16 cypher
      cypher' = B.concat [c1, B.replicate 16 0, c1, B.concat rest]
  msg <- catch (check cypher' `seq` return "") oops
  let (p1:_:p3:_) = chunksOf 16 msg
  return $ xorB p1 p3

ex27 = do
  key <- B.pack . take 16 . randoms <$> newStdGen
  let prefix  = "comment1=cooking%20MCs;userdata="
      postfix = ";comment2=%20like%20a%20pound%20of%20bacon"
      p = (key, key, prefix, postfix, 2)
      encoder = encryptionOracle p . B.filter (not . flip B.elem ";=")
      check = asciiCompliant (decryptionOracle p)
  k <- findKey check (encoder "this doesn't matter")
  print k
  print $ k==key

-- Ex 28

prop_words :: [Word32] -> Bool
prop_words w = w ==  toWord32 (fromWord32 w)

ex28 = do
  let sha1MAC = sha1 . B.append "secret key"
  print $ byteStringToHex $ sha1MAC "message"
  print $ byteStringToHex $ sha1MAC "message "
  print $ byteStringToHex $ sha1MAC "messagf"

-- Ex 29

findKeyLength :: (ByteString -> ByteString) -> Int64
findKeyLength mac = head $ filter guess [0..]
  where
  register = toWord32 $ mac ""
  guess 0 = mac "" == sha1 ""
  guess n = let key = B.replicate n 65
                keyPadding = B.drop n $ padSHA1 key
                hash1 = mac keyPadding
                lastChunk = last $ chunksOf 64 $ padSHA1 $ padSHA1 key
                hash2 = sha1With register lastChunk
            in hash1 == hash2

ex29 = do
  let original = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
      addon = ";admin=true;"
      sha1MAC = sha1 . B.append "secret key"

      n = findKeyLength sha1MAC
      fakeKey = B.replicate n 65
      padding = B.drop n $ padSHA1 $ B.append fakeKey original
      fakeEnd = last $ chunksOf 64 $ padSHA1 $ B.concat [fakeKey, padding, addon]
      register = toWord32 $ sha1MAC original
      forgedHash = sha1With register fakeEnd
      realHash = sha1MAC $ B.append padding addon
  print $ forgedHash == realHash

-- Ex 30


findKeyLengthMD4 :: (ByteString -> ByteString) -> Int64
findKeyLengthMD4 mac = head $ filter guess [0..]
  where
  register = map littleEndian $ toWord32 $ mac ""
  guess 0 = mac "" == md4 ""
  guess n = let key = B.replicate n 65
                keyPadding = B.drop n $ padMD4 key
                hash1 = mac keyPadding
                lastChunk = last $ chunksOf 64 $ padMD4 $ padMD4 key
                hash2 = md4With register lastChunk
            in hash1 == hash2

ex30 = do
  let original = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
      addon = ";admin=true;"
      mac = md4 . B.append "secret key"

      n = findKeyLengthMD4 mac
      fakeKey = B.replicate n 65
      padding = B.drop n $ padMD4 $ B.append fakeKey original
      fakeEnd = last $ chunksOf 64 $ padMD4 $ B.concat [fakeKey, padding, addon]
      register = map littleEndian $ toWord32 $ mac original
      forgedHash = md4With register fakeEnd
      realHash = mac $ B.append padding addon
  print $ forgedHash == realHash

-- Ex 31: run ./server first

ex31 = do
  let file = ";user=admin;"
  (Just hash) <- findHash file
  print $ byteStringToHex hash

findHash :: ByteString -> IO (Maybe ByteString)
findHash file = go 1 "" 0 0
  where
  getTime h i = do
    let h' = B.snoc h i
    (_, time) <- checkHash file (B.append h' "_")
    return (time, h')
  go 1 _ _ _ = do
    times <- mapM (getTime "") [0..255]
    let (tm, h) = maximum times
        t = (sum (map fst times) - tm) /255
        dt = tm - t
    go 2 h dt t
  go 21 h _ _ = do
    sol <- filterM ((fst <$>) . checkHash file . B.snoc h) [0..255]
    if null sol
      then return Nothing
      else return $ Just $ B.snoc h $ head sol
  go i h dt t = do
    timesSample <- mapM (getTime h) [0..4]
    let sampleT = sum (map fst timesSample) / 5
    print $ unwords $ [show i, byteStringToHex h]
    print $ (sampleT, t, dt)
    -- print $ take 5 $ map (\(t,h)->(t, byteStringToHex h)) $ timesSorted
    if sampleT < t + dt
      then return Nothing
      else do
        times <- mapM (getTime h) [5..255]
        let timesSorted = sortOn (negate . fst) (timesSample ++ times)
            t' = sum (map fst times) / 255
        next <- mapM (\(_, h') -> go (i+1) h' dt t' ) timesSorted
        return $ head $ filter (/= Nothing) next

checkHash :: ByteString -> ByteString -> IO (Bool, POSIXTime)
checkHash file hash = do
  let pre = "http://localhost:8000/test?file="
      sep = "&signature="
      request = pre ++ (byteStringToHex file) ++ sep ++ (byteStringToHex hash)
  t0 <- getPOSIXTime
  response <- simpleHTTP (getRequest $! request)
  t1 <- getPOSIXTime
  (c,_,_) <- getResponseCode response
  return (c == 2, t1 - t0)

main = ex32

ex32 = do
  let file = ";user=admin;"
  hash <- findHash' file
  print $ byteStringToHex hash

findHash' :: ByteString -> IO (ByteString)
findHash' file = do
  start <- mapM (getTime "") [0..255]
  exploreMax $ M.fromList start
  where
  getTime h i = do
    let h' = B.snoc h i
    (_, t1) <- checkHash file (B.append h' "_")
    (_, t2) <- checkHash file (B.append h' "_")
    return (min t1 t2 / (realToFrac (sqrt $ fromIntegral $ B.length h')),  h')
  exploreMax m = do
    let (t, b) = M.findMax m
    if B.length b == 19
      then do
        final <- mapM (checkHash file . B.snoc b) [0..255]
        let x = map snd $ filter (fst . fst) $ zip final [0..]
        if null x then exploreMax $ M.delete t m else return $ B.snoc b (head x)
      else do
        print $ byteStringToHex b
        next <- mapM (getTime b) [0..255]
        exploreMax $ M.union (M.delete t m) $ M.fromList next
-- 06 da 59 02 4e d6 fa da 0a c2 15 e8 52 4e 0c d2 ba fb ff f4
