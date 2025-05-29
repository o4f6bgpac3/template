import { writable } from 'svelte/store';

export interface Toast {
    id: string;
    message: string;
    type: 'success' | 'error' | 'warning' | 'info';
    duration?: number;
}

function createToastStore() {
    const { subscribe, update } = writable<Toast[]>([]);

    function add(toast: Omit<Toast, 'id'>) {
        const id = crypto.randomUUID();
        const newToast = { ...toast, id };

        update(toasts => [...toasts, newToast]);

        setTimeout(() => {
            update(toasts => toasts.filter(t => t.id !== id));
        }, toast.duration || 5000);

        return id;
    }

    return {
        subscribe,
        add,
        remove: (id: string) => {
            update(toasts => toasts.filter(t => t.id !== id));
        },
        clear: () => {
            update(() => []);
        },
        success: (message: string, duration?: number) => {
            return add({ message, type: 'success', duration });
        },
        error: (message: string, duration?: number) => {
            return add({ message, type: 'error', duration });
        },
        warning: (message: string, duration?: number) => {
            return add({ message, type: 'warning', duration });
        },
        info: (message: string, duration?: number) => {
            return add({ message, type: 'info', duration });
        }
    };
}

export const toast = createToastStore();