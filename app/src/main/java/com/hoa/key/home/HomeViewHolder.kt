package com.hoa.key.home

import android.view.View
import androidx.viewbinding.ViewBinding
import com.hoa.key.util.ViewBindingViewHolder

abstract class HomeViewHolder<T, VB : ViewBinding>(itemView: View, binding: VB) : ViewBindingViewHolder<T, VB, HomeAdapter.Listener>(itemView, binding)