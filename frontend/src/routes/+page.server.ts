import { buildInfo } from '$lib/build-info';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = () => {
    return {
        buildDate: new Date(buildInfo.buildTime).toISOString()
    };
};