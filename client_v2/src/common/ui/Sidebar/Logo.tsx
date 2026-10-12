import s from './styles.module.pcss';

type Props = {
    id: string;
};

/** Native GoreeCloud DNS product identity shared by the sidebar and headers. */
export const Logo = (props: Props) => (
    <div class={s.brand} role="img" aria-label="GoreeCloud DNS" data-logo-id={props.id}>
        <span class={s.brandMark} aria-hidden="true">GC</span>
        <span class={s.brandText} aria-hidden="true">
            <span class={s.brandName}>GoreeCloud</span>
            <span class={s.brandProduct}>DNS</span>
        </span>
    </div>
);
