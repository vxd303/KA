package com.hoa.key.home

import android.os.Bundle
import androidx.fragment.app.commit
import com.hoa.key.BuildConfig
import com.hoa.key.R
import com.hoa.key.app.AppBarFragmentActivity

class HomeActivity : AppBarFragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        supportActionBar?.subtitle = BuildConfig.VERSION_NAME

        if (savedInstanceState == null) {
            supportFragmentManager.commit {
                setReorderingAllowed(true)
                add(R.id.fragment_container, HomeFragment())
            }
        }
    }
}
