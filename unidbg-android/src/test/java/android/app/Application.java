package android.app;

import android.app.pm.PackageManager;

public class Application {
    public PackageManager getPackageManager() {
        return new PackageManager();
    }
    public String getPackageName() {
        return "com.shizhuang.duapp";
    }
}
