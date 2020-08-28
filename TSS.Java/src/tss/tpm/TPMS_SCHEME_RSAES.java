package tss.tpm;

import tss.*;


// -----------This is an auto-generated file: do not edit

//>>>

/** These are the RSA encryption schemes that only need a hash algorithm as a controlling parameter.  */
public class TPMS_SCHEME_RSAES extends TPMS_ENC_SCHEME_RSAES
{
    public TPMS_SCHEME_RSAES() {}

    /** @deprecated Use {@link #toBytes()} instead  */
    public byte[] toTpm () { return toBytes(); }

    /** Static marshaling helper  */
    public static TPMS_SCHEME_RSAES fromBytes (byte[] byteBuf) 
    {
        return new TpmBuffer(byteBuf).createObj(TPMS_SCHEME_RSAES.class);
    }

    /** @deprecated Use {@link #fromBytes()} instead  */
    public static TPMS_SCHEME_RSAES fromTpm (byte[] byteBuf)  { return fromBytes(byteBuf); }

    /** Static marshaling helper  */
    public static TPMS_SCHEME_RSAES fromTpm (TpmBuffer buf) 
    {
        return buf.createObj(TPMS_SCHEME_RSAES.class);
    }

    @Override
    public String toString()
    {
        TpmStructurePrinter _p = new TpmStructurePrinter("TPMS_SCHEME_RSAES");
        toStringInternal(_p, 1);
        _p.endStruct();
        return _p.toString();
    }
}

//<<<
