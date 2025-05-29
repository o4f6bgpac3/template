<script lang="ts">
    import {auth} from '$lib/stores/auth';
    import {onMount} from 'svelte';
    import {page} from '$app/state';

    import Login from './Login.svelte';
    import Register from './Register.svelte';
    import ForgotPassword from './ForgotPassword.svelte';
    import ResetPassword from './ResetPassword.svelte';
    import UserProfile from './UserProfile.svelte';

    type AuthMode = 'login' | 'register' | 'forgot' | 'reset';

    let currentMode: AuthMode = 'login';
    let resetToken = '';

    onMount(() => {
        const urlParams = new URLSearchParams(page.url.search);
        const token = urlParams.get('token');
        const mode = urlParams.get('mode');

        if (token && mode === 'reset') {
            resetToken = token;
            currentMode = 'reset';
        }
    });

    function handleModeSwitch(event: CustomEvent<'login' | 'register' | 'forgot' | 'reset'>) {
        currentMode = event.detail;
    }

    function handleAuthSuccess() {
        console.log('Authentication successful');
    }
</script>

<div class="min-h-screen">
    <div class="container mx-auto max-w-6xl">
        {#if $auth.user}
            <UserProfile/>
        {:else}
            <div class="text-center mb-8">
                <h1 class="text-4xl font-bold text-base-content mb-2">
                    {#if currentMode === 'login'}
                        Sign In to Your Account
                    {:else if currentMode === 'register'}
                        Create Your Account
                    {:else if currentMode === 'forgot'}
                        Reset Your Password
                    {:else if currentMode === 'reset'}
                        Set New Password
                    {/if}
                </h1>
                <p class="text-base-content/70">
                    {#if currentMode === 'login'}
                        Welcome back! Please sign in to continue.
                    {:else if currentMode === 'register'}
                        Join us today and get started in seconds.
                    {:else if currentMode === 'forgot'}
                        We'll help you get back into your account.
                    {:else if currentMode === 'reset'}
                        Almost there! Just set your new password.
                    {/if}
                </p>
            </div>

            {#if currentMode === 'login'}
                <Login
                        onswitchmode={handleModeSwitch}
                        onsuccess={handleAuthSuccess}
                />
            {:else if currentMode === 'register'}
                <Register
                        onswitchmode={handleModeSwitch}
                        onsuccess={handleAuthSuccess}
                />
            {:else if currentMode === 'forgot'}
                <ForgotPassword
                        onswitchmode={handleModeSwitch}
                />
            {:else if currentMode === 'reset'}
                <ResetPassword
                        token={resetToken}
                        onswitchmode={handleModeSwitch}
                />
            {/if}
        {/if}

        {#if $auth.error}
            <div class="toast toast-top toast-center">
                <div class="alert alert-error">
                    <svg xmlns="http://www.w3.org/2000/svg" class="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>{$auth.error}</span>
                </div>
            </div>
        {/if}
    </div>
</div>