package com.hashengineering.crypto;

import fr.cryptohash.Groestl512;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by Hash Engineering on 12/24/14 for the Groestl algorithm
 */
public class Groestl {

    private static final Logger log = LoggerFactory.getLogger(Groestl.class);
    private static boolean native_library_loaded = false;
    private static final Groestl512 digestGroestl = new Groestl512();

    static {

        try {
            System.loadLibrary("groestld");
            native_library_loaded = true;
        }
        catch(UnsatisfiedLinkError x)
        {
            native_library_loaded = false;
        }
        catch(Exception e)
        {
            native_library_loaded = false;
        }
    }

    public static byte[] digest(byte[] input, int offset, int length)
    {
        return native_library_loaded ? groestld_native(input, offset, length) : groestl(input, offset, length);
    }

    public static byte[] digest(byte[] input) {
            return native_library_loaded ? groestld_native(input, 0, input.length) : groestl(input);
    }

    static native byte [] groestld_native(byte [] input, int offset, int len);

    static byte [] groestl(byte header[])
    {
        Groestl512 hasher1 = new Groestl512();
        Groestl512 hasher2 = new Groestl512();
        byte [] hash1 = hasher1.digest(header);
        byte [] hash2 = hasher2.digest(hash1);
        return new Sha512Hash(hash2).trim256().getBytes();
    }

    static byte [] groestl(byte header[], int offset, int length)
    {
        digestGroestl.reset();
        digestGroestl.update(header, offset, length);
        byte [] hash512 = digestGroestl.digest();

        //digestGroestl.update(hash512);
        Sha512Hash doubleHash512 = new Sha512Hash(digestGroestl.digest(hash512));
        //Initialize

        return doubleHash512.trim256().getBytes();
    }

}
