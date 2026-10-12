import { render, screen } from '@solidjs/testing-library';
import { describe, expect, it } from 'vitest';

import { Logo } from 'panel/common/ui/Sidebar/Logo';
import { MANUAL_UPDATE_LINK, PRIVACY_POLICY_LINK, REPOSITORY, TERMS_LINK } from 'panel/helpers/constants';

describe('GoreeCloud DNS native identity and links', () => {
    it('exposes an accessible GoreeCloud product mark', () => {
        render(() => <Logo id="test" />);
        expect(screen.getByRole('img', { name: 'GoreeCloud DNS' })).toBeInTheDocument();
        expect(screen.getByText('GoreeCloud')).toBeInTheDocument();
        expect(screen.getByText('DNS')).toBeInTheDocument();
    });

    it('links to GoreeCloud support and release history', () => {
        expect(REPOSITORY.URL).toBe('https://github.com/GoreeCloud/DNS');
        expect(REPOSITORY.ISSUES).toBe('https://github.com/GoreeCloud/DNS/issues');
        expect(REPOSITORY.RELEASE_NOTES).toBe('https://github.com/GoreeCloud/DNS/releases');
    });

    it('links directly to source-controlled privacy and setup notices', () => {
        expect(PRIVACY_POLICY_LINK).toBe('https://github.com/GoreeCloud/DNS/blob/main/docs/PRIVACY.md');
        expect(TERMS_LINK).toBe('https://github.com/GoreeCloud/DNS/blob/main/docs/SELF_HOSTING.md');
        expect(PRIVACY_POLICY_LINK).not.toContain('adtidy.org');
        expect(TERMS_LINK).not.toContain('adtidy.org');
        expect(MANUAL_UPDATE_LINK).toBe('https://github.com/GoreeCloud/DNS/blob/main/docs/UPDATE_TRUST_BOUNDARY.md');
    });
});
