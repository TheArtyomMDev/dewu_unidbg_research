package android.app;

import java.util.ArrayList;
import java.util.List;

public class ActivityThread {
    static ActivityThread currentActivityThread() {

        return new ActivityThread();
    }

    Application getApplication() {
        return new Application();
    }
}
