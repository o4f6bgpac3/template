import { writeFileSync } from 'fs';

const buildInfo = {
    buildTime: new Date().toISOString(),
    timestamp: Date.now()
};

const content = `export const buildInfo = ${JSON.stringify(buildInfo, null, 2)} as const;

export type BuildInfo = typeof buildInfo;
`;

writeFileSync('src/lib/build-info.ts', content);