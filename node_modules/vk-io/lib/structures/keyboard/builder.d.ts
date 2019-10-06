import { KeyboardButton, IKeyboardTextButtonOptions, IKeyboardLocationRequestButtonOptions, IKeyboardVKPayButtonOptions, IKeyboardApplicationButtonOptions } from './types';
export default class KeyboardBuilder {
    /**
     * Does the keyboard close after pressing the button
     */
    protected isOneTime: boolean;
    /**
     * Rows with all buttons
     */
    protected rows: KeyboardButton[][];
    /**
     * Current row of buttons
     */
    protected currentRow: KeyboardButton[];
    /**
     * Returns custom tag
     */
    readonly [Symbol.toStringTag]: string;
    /**
     * Text button, can be colored
     *
     * ```ts
     * builder.textButton({
     *  label: 'Buy a coffee',
     *  payload: {
     *   command: 'buy',
     *   item: 'coffee'
     *  },
     *  color: Keyboard.POSITIVE_COLOR
     * });
     * ```
     */
    textButton({ label, payload: rawPayload, color }: IKeyboardTextButtonOptions): this;
    /**
     * User location request button, occupies the entire keyboard width
     *
     * ```ts
     * builder.locationRequestButton({
     *  payload: {
     *   command: 'order_delivery'
     *  }
     * })
     * ```
     */
    locationRequestButton({ payload: rawPayload }: IKeyboardLocationRequestButtonOptions): this;
    /**
     * VK Pay button, occupies the entire keyboard width
     *
     * ```ts
     * builder.payButton({
     *  hash: {
     *   action: 'transfer-to-group',
     *   group_id: 1,
     *   aid: 10
     *  }
     * })
     * ```
     */
    payButton({ hash: rawHash }: IKeyboardVKPayButtonOptions): this;
    /**
     * VK Apps button, occupies the entire keyboard width
     *
     * ```ts
     * builder.applicationButton({
     *  label: 'LiveWidget',
     *  appId: 6232540,
     *  ownerId: -157525928
     * })
     * ```
     */
    applicationButton({ label, appId, ownerId, hash }: IKeyboardApplicationButtonOptions): this;
    /**
     * Saves the current row of buttons in the general rows
     */
    row(): this;
    /**
     * Sets the keyboard to close after pressing
     *
     * ```ts
     *  builder.oneTime();
     *
     *  builder.oneTime(false);
     * ```
     */
    oneTime(enabled?: boolean): this;
    /**
     * Clones the builder with all the settings
     */
    clone(): KeyboardBuilder;
    /**
     * Returns a string to keyboard a VK
     */
    toString(): string;
    /**
     * Adds a button to the current row
     */
    protected addButton(button: KeyboardButton): this;
    /**
     * Adds a wide button to the new row
     */
    protected addWideButton(button: KeyboardButton): this;
}
