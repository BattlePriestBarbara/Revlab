package com.revlab.mobile;

import android.view.View;

/**
 * The "连接" button's listener, as a top-level class on purpose.
 *
 * An anonymous {@code View.OnClickListener} would be the obvious way to write
 * this in one place, but it puts an InnerClasses attribute in the class file and
 * R8 (d8) in build-tools then fails to compile the package -- see the note in
 * MainActivity. One small class is a cheap way to keep the toolchain happy.
 */
class ConnectListener implements View.OnClickListener {

    private final MainActivity activity;

    ConnectListener(MainActivity activity) {
        this.activity = activity;
    }

    @Override
    public void onClick(View view) {
        activity.loadFromBar();
    }
}
