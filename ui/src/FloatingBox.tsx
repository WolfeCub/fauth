import { ParentComponent } from "solid-js";

export const FloatingBox: ParentComponent = (props) => {
    return (
        <div class="flex h-screen">
            <div class="m-auto flex flex-col shadow-lg p-10">
                {props.children}
            </div>
        </div>
    );
};
