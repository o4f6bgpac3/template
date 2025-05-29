<script lang="ts">
    import {auth} from '$lib/stores/auth';
    import {page} from '$app/state';
    import {Home, LogIn, Settings, Shield, User, UserPlus} from 'lucide-svelte';

    interface MenuItem {
        href: string;
        label: string;
        icon: any;
        roles?: string[];
        authRequired?: boolean;
        guestOnly?: boolean;
    }

    const menuItems: MenuItem[] = [
        {
            href: '/',
            label: 'Home',
            icon: Home,
        },
        {
            href: '/profile',
            label: 'Profile',
            icon: User,
            authRequired: true
        },
        {
            href: '/settings',
            label: 'Settings',
            icon: Settings,
            authRequired: true
        },
        {
            href: '/admin',
            label: 'Admin Panel',
            icon: Shield,
            roles: ['admin']
        },
    ];

    function shouldShowMenuItem(item: MenuItem): boolean {
        const isAuthenticated = !!$auth.user;

        if (item.guestOnly && isAuthenticated) return false;

        if (item.authRequired && !isAuthenticated) return false;

        if (item.roles && item.roles.length > 0) {
            if (!isAuthenticated) return false;
            return item.roles.some(role => $auth.user?.roles.includes(role));
        }

        return true;
    }

    const filteredMenuItems = $derived(menuItems.filter(shouldShowMenuItem));
    const currentPath = $derived(page.url.pathname);
</script>

<aside class="h-full overflow-y-auto">
    <nav class="p-4">
        <ul class="menu space-y-2 w-full">
            {#each filteredMenuItems as item}
                {@const Icon = item.icon}
                <li>
                    <a
                            href={item.href}
                            class="flex items-center gap-3 p-3 rounded-lg transition-colors"
                            class:bg-primary={currentPath === item.href}
                            class:text-primary-content={currentPath === item.href}
                            class:hover:bg-base-300={currentPath !== item.href}
                    >
                        <Icon size="20"/>
                        {item.label}
                    </a>
                </li>
            {/each}
        </ul>
    </nav>
</aside>