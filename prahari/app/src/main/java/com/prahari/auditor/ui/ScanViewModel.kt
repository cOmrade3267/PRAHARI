package com.prahari.auditor.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.prahari.auditor.core.AppRecord
import com.prahari.auditor.core.PermissionDiff
import com.prahari.auditor.core.ScanSnapshot
import com.prahari.auditor.di.ServiceLocator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class ScanUiState(
    val scanning: Boolean = false,
    val done: Int = 0,
    val total: Int = 0,
    val apps: List<AppRecord> = emptyList(),
    val includeSystem: Boolean = false,
    val message: String? = "No scan yet. Tap “Scan device” to list every app with its permissions and special access.",
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = ServiceLocator.repository(app)

    private val _state = MutableStateFlow(ScanUiState())
    val state: StateFlow<ScanUiState> = _state.asStateFlow()

    /** Trust Timeline + permission diff for the currently-open app detail screen. */
    private val _history = MutableStateFlow<List<ScanSnapshot>>(emptyList())
    val history: StateFlow<List<ScanSnapshot>> = _history.asStateFlow()
    private val _newlySensitive = MutableStateFlow<Set<String>>(emptySet())
    val newlySensitive: StateFlow<Set<String>> = _newlySensitive.asStateFlow()

    fun loadHistory(packageName: String) {
        viewModelScope.launch {
            val h = withContext(Dispatchers.IO) { repo.history(packageName) }
            _history.value = h
            _newlySensitive.value = PermissionDiff.newlySensitive(h)
        }
    }

    fun setIncludeSystem(value: Boolean) = _state.update { it.copy(includeSystem = value) }

    fun scan() {
        if (_state.value.scanning) return
        _state.update { it.copy(scanning = true, done = 0, total = 0, message = null) }
        viewModelScope.launch {
            val auditor = ServiceLocator.auditor(getApplication<Application>())
            val now = System.currentTimeMillis()
            val result = withContext(Dispatchers.Default) {
                auditor.runScan(_state.value.includeSystem, now) { done, total ->
                    _state.update { it.copy(done = done, total = total) }
                }
            }
            _state.update {
                it.copy(
                    scanning = false,
                    apps = result,
                    message = if (result.isEmpty())
                        "Scan found no user apps — try enabling “System apps”."
                    else null,
                )
            }
        }
    }

    fun appByPackage(pkg: String): AppRecord? = _state.value.apps.firstOrNull { it.packageName == pkg }
}
