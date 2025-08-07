package android.app.pm;

import android.content.pm.Signature;

public class PackageInfo {
    public Signature[] signatures;

    public PackageInfo() {
        this.signatures = new Signature[]{new Signature()};
    }

}
