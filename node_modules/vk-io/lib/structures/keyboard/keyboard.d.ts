import KeyboardBuilder from './builder';
import { IKeyboardProxyButton, IKeyboardTextButtonOptions, IKeyboardLocationRequestButtonOptions, IKeyboardVKPayButtonOptions, IKeyboardApplicationButtonOptions, ButtonColor } from './types';
export default class Keyboard {
    /**
     * Returns custom tag
     */
    readonly [Symbol.toStringTag]: string;
    /**
     * @deprecated Use Keyboard.SECONDARY_COLOR instead
     */
    static readonly DEFAULT_COLOR: ButtonColor.SECONDARY;
    /**
     * The white button, indicates secondary action
     *
     * Hex color #FFFFFF
     */
    static readonly SECONDARY_COLOR: ButtonColor.SECONDARY;
    /**
     * The blue button, indicates the main action
     *
     * Hex color #5181B8
     */
    static readonly PRIMARY_COLOR: ButtonColor.PRIMARY;
    /**
     * The red button, indicates a dangerous or a negative action (reject, delete, etc...)
     *
     * Hex color #E64646
     */
    static readonly NEGATIVE_COLOR: ButtonColor.NEGATIVE;
    /**
     * The green button, indicates a agree, confirm, ...etc
     *
     * Hex color #4BB34B
     */
    static readonly POSITIVE_COLOR: ButtonColor.POSITIVE;
    /**
     * Returns keyboard builder
     */
    static builder(): KeyboardBuilder;
    /**
     * Assembles a builder of buttons
     */
    static keyboard(rows: (IKeyboardProxyButton | IKeyboardProxyButton[])[]): KeyboardBuilder;
    /**
     * Text button, can be colored
     */
    static textButton(options: IKeyboardTextButtonOptions): IKeyboardProxyButton;
    /**
     * User location request button, occupies the entire keyboard width
     */
    static locationRequestButton(options: IKeyboardLocationRequestButtonOptions): IKeyboardProxyButton;
    /**
     * VK Pay button, occupies the entire keyboard width
     */
    static payButton(options: IKeyboardVKPayButtonOptions): IKeyboardProxyButton;
    /**
     * VK Apps button, occupies the entire keyboard width
     */
    static applicationButton(options: IKeyboardApplicationButtonOptions): IKeyboardProxyButton;
}
